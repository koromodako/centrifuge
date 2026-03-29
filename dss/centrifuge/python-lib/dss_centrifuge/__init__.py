"""DSS Centrifuge Plugin Shared Library"""

import logging as _LOGGER
from collections.abc import AsyncIterator, Awaitable, Callable
from json import dumps
from typing import Any

from dataiku import Dataset
from dataiku.core.dataset_write import DatasetWriter
from dataiku.customrecipe import (
    get_input_names_for_role,
    get_output_names_for_role,
    get_plugin_config,
    get_recipe_config,
)
from pandas import DataFrame

_PLUGIN_CONF = get_plugin_config()
_RECIPE_CONF = get_recipe_config()
_DEFAULT_CHUNKSIZE = 500
_DEFAULT_INFER_WITH_PANDAS = False


def get_config_value(name: str, default: Any = None) -> Any:
    """Retrieve configuration value from recipe, plugin or default"""
    # try recipe config first (overrides plugin config)
    value = _RECIPE_CONF.get(name)
    if value is not None:
        return value
    # or try plugin config (global config)
    value = _PLUGIN_CONF.get(name)
    if value is not None:
        return value
    # or return default
    return default


def get_input_dataset(role: str):
    """Retrieve input dataset"""
    names = get_input_names_for_role(role)
    if not names:
        return None
    if len(names) > 1:
        _LOGGER.warning("more than one input dataset name for role: %s", role)
    return Dataset(names[0])


def get_output_dataset(role: str):
    """Retrieve output dataset"""
    names = get_output_names_for_role(role)
    if not names:
        return None
    if len(names) > 1:
        _LOGGER.warning("more than one output dataset name for role: %s", role)
    return Dataset(names[0])


async def async_routine_identity(input_df: DataFrame, _) -> DataFrame:
    """Async routine identity function"""
    return input_df


async def async_iter_dataframes(
    input_ds: Dataset,
    chunksize: int = _DEFAULT_CHUNKSIZE,
    **kwargs,
):
    """Iterate dataset dataframes (use when async iterator is needed)"""
    if 'infer_with_pandas' not in kwargs:
        kwargs['infer_with_pandas'] = _DEFAULT_INFER_WITH_PANDAS
    for input_df in input_ds.iter_dataframes(chunksize=chunksize, **kwargs):
        yield input_df


def generic_df_write(
    output_ds: Dataset,
    ds_writer: DatasetWriter,
    output_df: DataFrame,
    first: bool,
) -> bool:
    """Perform generic write on output dataset"""
    if output_df.empty:
        return False
    if first:
        output_ds.write_schema_from_dataframe(output_df)
    ds_writer.write_dataframe(output_df)
    return True


RoutineContext = dict | None
AsyncRoutine = Callable[[DataFrame, RoutineContext], Awaitable[DataFrame]]


async def async_generic_iterator_processor(
    output_ds: Dataset,
    async_df_iterator: AsyncIterator[DataFrame],
    async_routine: AsyncRoutine = async_routine_identity,
    routine_ctx: RoutineContext = None,
):
    """Process dataframes from given async iterator"""
    first = True
    with output_ds.get_writer() as ds_writer:
        async for input_df in async_df_iterator:
            output_df = await async_routine(input_df, routine_ctx)
            written = generic_df_write(output_ds, ds_writer, output_df, first)
            first = first and not written


async def async_generic_dataset_processor(
    input_ds: Dataset,
    output_ds: Dataset,
    async_routine: AsyncRoutine = async_routine_identity,
    routine_ctx: RoutineContext = None,
    chunksize: int = _DEFAULT_CHUNKSIZE,
    **kwargs,
):
    """Process input dataset in chunks"""
    await async_generic_iterator_processor(
        output_ds,
        async_iter_dataframes(input_ds, chunksize=chunksize, **kwargs),
        async_routine,
        routine_ctx,
    )


def serialize(value: Any):
    """Serialize value"""
    if isinstance(value, set):
        value = list(sorted(value))
    if isinstance(value, (dict, list)):
        value = dumps(value)
    return value
