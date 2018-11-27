/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_qsort.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: amaindro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/08/24 17:50:54 by amaindro          #+#    #+#             */
/*   Updated: 2017/10/04 16:49:58 by amaindro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void		swap(void *a, void *b)
{
	int		tmp;

	tmp = *(int*)a;
	*(int*)a = *(int*)b;
	*(int*)b = tmp;
}

void			ft_qsort(void *base, size_t nel, size_t width,
		int (*compar)(const void *, const void *))
{
	int		i;
	int		j;
	void	*pivot;

	pivot = base + width * (nel - 1);
	i = -1;
	j = 0;
	while ((unsigned int)j < nel - 1)
	{
		if ((*compar)(base + width * j, pivot) <= 0)
		{
			i++;
			swap(base + width * j, base + width * i);
		}
		j++;
	}
	swap(pivot, base + width * (i + 1));
	if (i >= 1)
		ft_qsort(base, i + 1, width, compar);
	if ((nel - (i + 1)) > 1)
		ft_qsort(base + width * (i + 1), nel - (i + 1), width, compar);
}
